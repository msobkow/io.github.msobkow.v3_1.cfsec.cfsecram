
// Description: Java 25 in-memory RAM DbIO implementation for SecUser.

/*
 *	io.github.msobkow.CFSec
 *
 *	Copyright (c) 2016-2026 Mark Stephen Sobkow
 *	
 *	Mark's Code Fractal 3.1 CFSec - Security Services
 *	
 *	This file is part of Mark's Code Fractal CFSec.
 *	
 *	Mark's Code Fractal CFSec is available under dual commercial license from
 *	Mark Stephen Sobkow, or under the terms of the GNU Library General Public License,
 *	Version 3 or later.
 *	
 *	Mark's Code Fractal CFSec is free software: you can redistribute it and/or
 *	modify it under the terms of the GNU Library General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *	
 *	Mark's Code Fractal CFSec is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *	
 *	You should have received a copy of the GNU Library General Public License
 *	along with Mark's Code Fractal CFSec.  If not, see <https://www.gnu.org/licenses/>.
 *	
 *	If you wish to modify and use this code without publishing your changes in order to
 *	tie it to proprietary code, please contact Mark Stephen Sobkow
 *	for a commercial license at mark.sobkow@gmail.com
 *	
 */

package io.github.msobkow.v3_1.cfsec.cfsecram;

import java.math.*;
import java.sql.*;
import java.text.*;
import java.time.*;
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsec.buff.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamSecUserTable in-memory RAM DbIO implementation
 *	for SecUser.
 */
public class CFSecRamSecUserTable
	implements ICFSecSecUserTable
{
	private ICFSecSchema schema;
	private Map< CFLibDbKeyHash256,
				CFSecBuffSecUser > dictByPKey
		= new HashMap< CFLibDbKeyHash256,
				CFSecBuffSecUser >();
	private Map< CFSecBuffSecUserByULoginIdxKey,
			CFSecBuffSecUser > dictByULoginIdx
		= new HashMap< CFSecBuffSecUserByULoginIdxKey,
			CFSecBuffSecUser >();
	private Map< CFSecBuffSecUserByEMConfIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >> dictByEMConfIdx
		= new HashMap< CFSecBuffSecUserByEMConfIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >>();
	private Map< CFSecBuffSecUserByPwdResetIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >> dictByPwdResetIdx
		= new HashMap< CFSecBuffSecUserByPwdResetIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >>();
	private Map< CFSecBuffSecUserByDefDevIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >> dictByDefDevIdx
		= new HashMap< CFSecBuffSecUserByDefDevIdxKey,
				Map< CFLibDbKeyHash256,
					CFSecBuffSecUser >>();

	public CFSecRamSecUserTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser Buff )
	{
		final String S_ProcName = "createSecUser";
		CFLibDbKeyHash256 pkey = schema.getFactorySecUser().newPKey();
		pkey.setRequiredSecUserId( schema.nextSecUserIdGen() );
		Buff.setRequiredSecUserId( pkey.getRequiredSecUserId() );
		CFSecBuffSecUserByULoginIdxKey keyULoginIdx = schema.getFactorySecUser().newULoginIdxKey();
		keyULoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		CFSecBuffSecUserByEMConfIdxKey keyEMConfIdx = schema.getFactorySecUser().newEMConfIdxKey();
		keyEMConfIdx.setOptionalEMailConfirmUuid6( Buff.getOptionalEMailConfirmUuid6() );

		CFSecBuffSecUserByPwdResetIdxKey keyPwdResetIdx = schema.getFactorySecUser().newPwdResetIdxKey();
		keyPwdResetIdx.setOptionalPasswordResetUuid6( Buff.getOptionalPasswordResetUuid6() );

		CFSecBuffSecUserByDefDevIdxKey keyDefDevIdx = schema.getFactorySecUser().newDefDevIdxKey();
		keyDefDevIdx.setOptionalDfltDevUserId( Buff.getOptionalDfltDevUserId() );
		keyDefDevIdx.setOptionalDfltDevName( Buff.getOptionalDfltDevName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByULoginIdx.containsKey( keyULoginIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"SecUserLoginIdx",
				keyULoginIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByULoginIdx.put( keyULoginIdx, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictEMConfIdx;
		if( dictByEMConfIdx.containsKey( keyEMConfIdx ) ) {
			subdictEMConfIdx = dictByEMConfIdx.get( keyEMConfIdx );
		}
		else {
			subdictEMConfIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByEMConfIdx.put( keyEMConfIdx, subdictEMConfIdx );
		}
		subdictEMConfIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictPwdResetIdx;
		if( dictByPwdResetIdx.containsKey( keyPwdResetIdx ) ) {
			subdictPwdResetIdx = dictByPwdResetIdx.get( keyPwdResetIdx );
		}
		else {
			subdictPwdResetIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByPwdResetIdx.put( keyPwdResetIdx, subdictPwdResetIdx );
		}
		subdictPwdResetIdx.put( pkey, Buff );

		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictDefDevIdx;
		if( dictByDefDevIdx.containsKey( keyDefDevIdx ) ) {
			subdictDefDevIdx = dictByDefDevIdx.get( keyDefDevIdx );
		}
		else {
			subdictDefDevIdx = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByDefDevIdx.put( keyDefDevIdx, subdictDefDevIdx );
		}
		subdictDefDevIdx.put( pkey, Buff );

	}

	public ICFSecSecUser readDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerived";
		ICFSecSecUser buff;
		if( dictByPKey.containsKey( PKey ) ) {
			buff = dictByPKey.get( PKey );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecUser lockDerived( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerived";
		CFLibDbKeyHash256 key = schema.getFactorySecUser().newPKey();
		key.setRequiredSecUserId( PKey.getRequiredSecUserId() );
		ICFSecSecUser buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecUser[] readAllDerived( ICFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamSecUser.readAllDerived";
		ICFSecSecUser[] retList = new ICFSecSecUser[ dictByPKey.values().size() ];
		Iterator< ICFSecSecUser > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public ICFSecSecUser readDerivedByULoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByULoginIdx";
		CFSecBuffSecUserByULoginIdxKey key = schema.getFactorySecUser().newULoginIdxKey();
		key.setRequiredLoginId( LoginId );

		ICFSecSecUser buff;
		if( dictByULoginIdx.containsKey( key ) ) {
			buff = dictByULoginIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecUser[] readDerivedByEMConfIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByEMConfIdx";
		CFSecBuffSecUserByEMConfIdxKey key = schema.getFactorySecUser().newEMConfIdxKey();
		key.setOptionalEMailConfirmUuid6( EMailConfirmUuid6 );

		ICFSecSecUser[] recArray;
		if( dictByEMConfIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictEMConfIdx
				= dictByEMConfIdx.get( key );
			recArray = new ICFSecSecUser[ subdictEMConfIdx.size() ];
			Iterator< ICFSecSecUser > iter = subdictEMConfIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictEMConfIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByEMConfIdx.put( key, subdictEMConfIdx );
			recArray = new ICFSecSecUser[0];
		}
		return( recArray );
	}

	public ICFSecSecUser[] readDerivedByPwdResetIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByPwdResetIdx";
		CFSecBuffSecUserByPwdResetIdxKey key = schema.getFactorySecUser().newPwdResetIdxKey();
		key.setOptionalPasswordResetUuid6( PasswordResetUuid6 );

		ICFSecSecUser[] recArray;
		if( dictByPwdResetIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictPwdResetIdx
				= dictByPwdResetIdx.get( key );
			recArray = new ICFSecSecUser[ subdictPwdResetIdx.size() ];
			Iterator< ICFSecSecUser > iter = subdictPwdResetIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictPwdResetIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByPwdResetIdx.put( key, subdictPwdResetIdx );
			recArray = new ICFSecSecUser[0];
		}
		return( recArray );
	}

	public ICFSecSecUser[] readDerivedByDefDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByDefDevIdx";
		CFSecBuffSecUserByDefDevIdxKey key = schema.getFactorySecUser().newDefDevIdxKey();
		key.setOptionalDfltDevUserId( DfltDevUserId );
		key.setOptionalDfltDevName( DfltDevName );

		ICFSecSecUser[] recArray;
		if( dictByDefDevIdx.containsKey( key ) ) {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictDefDevIdx
				= dictByDefDevIdx.get( key );
			recArray = new ICFSecSecUser[ subdictDefDevIdx.size() ];
			Iterator< ICFSecSecUser > iter = subdictDefDevIdx.values().iterator();
			int idx = 0;
			while( iter.hasNext() ) {
				recArray[ idx++ ] = iter.next();
			}
		}
		else {
			Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdictDefDevIdx
				= new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByDefDevIdx.put( key, subdictDefDevIdx );
			recArray = new ICFSecSecUser[0];
		}
		return( recArray );
	}

	public ICFSecSecUser readDerivedByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUser.readDerivedByIdIdx() ";
		CFLibDbKeyHash256 key = schema.getFactorySecUser().newPKey();
		key.setRequiredSecUserId( SecUserId );

		ICFSecSecUser buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecUser readBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuff";
		ICFSecSecUser buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a011" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecUser lockBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 PKey )
	{
		final String S_ProcName = "lockBuff";
		ICFSecSecUser buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a011" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public ICFSecSecUser[] readAllBuff( ICFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamSecUser.readAllBuff";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	/**
	 *	Read a page of all the specific SecUser buffer instances.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@return All the specific SecUser instances in the database accessible for the Authorization.
	 */
	public ICFSecSecUser[] pageAllBuff( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageAllBuff";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public ICFSecSecUser readBuffByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 SecUserId )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByIdIdx() ";
		ICFSecSecUser buff = readDerivedByIdIdx( Authorization,
			SecUserId );
		if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
			return( (ICFSecSecUser)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecUser readBuffByULoginIdx( ICFSecAuthorization Authorization,
		String LoginId )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByULoginIdx() ";
		ICFSecSecUser buff = readDerivedByULoginIdx( Authorization,
			LoginId );
		if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
			return( (ICFSecSecUser)buff );
		}
		else {
			return( null );
		}
	}

	public ICFSecSecUser[] readBuffByEMConfIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByEMConfIdx() ";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readDerivedByEMConfIdx( Authorization,
			EMailConfirmUuid6 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
				filteredList.add( (ICFSecSecUser)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	public ICFSecSecUser[] readBuffByPwdResetIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6 )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByPwdResetIdx() ";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readDerivedByPwdResetIdx( Authorization,
			PasswordResetUuid6 );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
				filteredList.add( (ICFSecSecUser)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	public ICFSecSecUser[] readBuffByDefDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName )
	{
		final String S_ProcName = "CFSecRamSecUser.readBuffByDefDevIdx() ";
		ICFSecSecUser buff;
		ArrayList<ICFSecSecUser> filteredList = new ArrayList<ICFSecSecUser>();
		ICFSecSecUser[] buffList = readDerivedByDefDevIdx( Authorization,
			DfltDevUserId,
			DfltDevName );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a011" ) ) {
				filteredList.add( (ICFSecSecUser)buff );
			}
		}
		return( filteredList.toArray( new ICFSecSecUser[0] ) );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key EMConfIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	EMailConfirmUuid6	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecUser[] pageBuffByEMConfIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 EMailConfirmUuid6,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageBuffByEMConfIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key PwdResetIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	PasswordResetUuid6	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecUser[] pageBuffByPwdResetIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 PasswordResetUuid6,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageBuffByPwdResetIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	/**
	 *	Read a page array of the specific SecUser buffer instances identified by the duplicate key DefDevIdx.
	 *
	 *	@param	Authorization	The session authorization information.
	 *
	 *	@param	DfltDevUserId	The SecUser key attribute of the instance generating the id.
	 *
	 *	@param	DfltDevName	The SecUser key attribute of the instance generating the id.
	 *
	 *	@return An array of derived buffer instances for the specified key, potentially with 0 elements in the set.
	 *
	 *	@throws	CFLibNotSupportedException thrown by client-side implementations.
	 */
	public ICFSecSecUser[] pageBuffByDefDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 DfltDevUserId,
		String DfltDevName,
		CFLibDbKeyHash256 priorSecUserId )
	{
		final String S_ProcName = "pageBuffByDefDevIdx";
		throw new CFLibNotImplementedYetException( getClass(), S_ProcName );
	}

	public void updateSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser Buff )
	{
		CFLibDbKeyHash256 pkey = schema.getFactorySecUser().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		ICFSecSecUser existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateSecUser",
				"Existing record not found",
				"SecUser",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateSecUser",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecBuffSecUserByULoginIdxKey existingKeyULoginIdx = schema.getFactorySecUser().newULoginIdxKey();
		existingKeyULoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecUserByULoginIdxKey newKeyULoginIdx = schema.getFactorySecUser().newULoginIdxKey();
		newKeyULoginIdx.setRequiredLoginId( Buff.getRequiredLoginId() );

		CFSecBuffSecUserByEMConfIdxKey existingKeyEMConfIdx = schema.getFactorySecUser().newEMConfIdxKey();
		existingKeyEMConfIdx.setOptionalEMailConfirmUuid6( existing.getOptionalEMailConfirmUuid6() );

		CFSecBuffSecUserByEMConfIdxKey newKeyEMConfIdx = schema.getFactorySecUser().newEMConfIdxKey();
		newKeyEMConfIdx.setOptionalEMailConfirmUuid6( Buff.getOptionalEMailConfirmUuid6() );

		CFSecBuffSecUserByPwdResetIdxKey existingKeyPwdResetIdx = schema.getFactorySecUser().newPwdResetIdxKey();
		existingKeyPwdResetIdx.setOptionalPasswordResetUuid6( existing.getOptionalPasswordResetUuid6() );

		CFSecBuffSecUserByPwdResetIdxKey newKeyPwdResetIdx = schema.getFactorySecUser().newPwdResetIdxKey();
		newKeyPwdResetIdx.setOptionalPasswordResetUuid6( Buff.getOptionalPasswordResetUuid6() );

		CFSecBuffSecUserByDefDevIdxKey existingKeyDefDevIdx = schema.getFactorySecUser().newDefDevIdxKey();
		existingKeyDefDevIdx.setOptionalDfltDevUserId( existing.getOptionalDfltDevUserId() );
		existingKeyDefDevIdx.setOptionalDfltDevName( existing.getOptionalDfltDevName() );

		CFSecBuffSecUserByDefDevIdxKey newKeyDefDevIdx = schema.getFactorySecUser().newDefDevIdxKey();
		newKeyDefDevIdx.setOptionalDfltDevUserId( Buff.getOptionalDfltDevUserId() );
		newKeyDefDevIdx.setOptionalDfltDevName( Buff.getOptionalDfltDevName() );

		// Check unique indexes

		if( ! existingKeyULoginIdx.equals( newKeyULoginIdx ) ) {
			if( dictByULoginIdx.containsKey( newKeyULoginIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateSecUser",
					"SecUserLoginIdx",
					newKeyULoginIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByULoginIdx.remove( existingKeyULoginIdx );
		dictByULoginIdx.put( newKeyULoginIdx, Buff );

		subdict = dictByEMConfIdx.get( existingKeyEMConfIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByEMConfIdx.containsKey( newKeyEMConfIdx ) ) {
			subdict = dictByEMConfIdx.get( newKeyEMConfIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByEMConfIdx.put( newKeyEMConfIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByPwdResetIdx.get( existingKeyPwdResetIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByPwdResetIdx.containsKey( newKeyPwdResetIdx ) ) {
			subdict = dictByPwdResetIdx.get( newKeyPwdResetIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByPwdResetIdx.put( newKeyPwdResetIdx, subdict );
		}
		subdict.put( pkey, Buff );

		subdict = dictByDefDevIdx.get( existingKeyDefDevIdx );
		if( subdict != null ) {
			subdict.remove( pkey );
		}
		if( dictByDefDevIdx.containsKey( newKeyDefDevIdx ) ) {
			subdict = dictByDefDevIdx.get( newKeyDefDevIdx );
		}
		else {
			subdict = new HashMap< CFLibDbKeyHash256, CFSecBuffSecUser >();
			dictByDefDevIdx.put( newKeyDefDevIdx, subdict );
		}
		subdict.put( pkey, Buff );

	}

	public void deleteSecUser( ICFSecAuthorization Authorization,
		ICFSecSecUser Buff )
	{
		final String S_ProcName = "CFSecRamSecUserTable.deleteSecUser() ";
		String classCode;
		CFLibDbKeyHash256 pkey = schema.getFactorySecUser().newPKey();
		pkey.setRequiredSecUserId( Buff.getRequiredSecUserId() );
		ICFSecSecUser existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteSecUser",
				pkey );
		}
					{
						CFSecSecUserBuff editBuff = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
						existing.getRequiredSecUserId() );
						editBuff.setOptionalDfltDevUserId( null );
						editBuff.setOptionalDfltDevName( null );
						classCode = editBuff.getClassCode();
						if( classCode.equals( "a011" ) ) {
							schema.getTableSecUser().updateSecUser( Authorization, editBuff );
						}
						else {
							new CFLibUnsupportedClassException( getClass(),
								S_ProcName,
								"Unrecognized ClassCode \"" + classCode + "\"" );
						}
					}
		CFSecSecUserBuff editSubobj = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
			existing.getRequiredSecUserId() );
			editSubobj.setOptionalDfltDevUserId( null );
			editSubobj.setOptionalDfltDevName( null );
		classCode = editSubobj.getClassCode();
		if( classCode.equals( "a011" ) ) {
			schema.getTableSecUser().updateSecUser( Authorization, editSubobj );
		}
		else {
			new CFLibUnsupportedClassException( getClass(),
				S_ProcName,
				"Unrecognized ClassCode \"" + classCode + "\"" );
		}
		existing = editSubobj;
					schema.getTableTSecGrpMemb().deleteTSecGrpMembByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecGrpMemb().deleteSecGrpMembByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecSession().deleteSecSessionBySecUserIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecSession().deleteSecSessionBySecProxyIdx( Authorization,
						existing.getRequiredSecUserId() );
					schema.getTableSecDevice().deleteSecDeviceByUserIdx( Authorization,
						existing.getRequiredSecUserId() );
		CFSecBuffSecUserByULoginIdxKey keyULoginIdx = schema.getFactorySecUser().newULoginIdxKey();
		keyULoginIdx.setRequiredLoginId( existing.getRequiredLoginId() );

		CFSecBuffSecUserByEMConfIdxKey keyEMConfIdx = schema.getFactorySecUser().newEMConfIdxKey();
		keyEMConfIdx.setOptionalEMailConfirmUuid6( existing.getOptionalEMailConfirmUuid6() );

		CFSecBuffSecUserByPwdResetIdxKey keyPwdResetIdx = schema.getFactorySecUser().newPwdResetIdxKey();
		keyPwdResetIdx.setOptionalPasswordResetUuid6( existing.getOptionalPasswordResetUuid6() );

		CFSecBuffSecUserByDefDevIdxKey keyDefDevIdx = schema.getFactorySecUser().newDefDevIdxKey();
		keyDefDevIdx.setOptionalDfltDevUserId( existing.getOptionalDfltDevUserId() );
		keyDefDevIdx.setOptionalDfltDevName( existing.getOptionalDfltDevName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFLibDbKeyHash256, CFSecBuffSecUser > subdict;

		dictByPKey.remove( pkey );

		dictByULoginIdx.remove( keyULoginIdx );

		subdict = dictByEMConfIdx.get( keyEMConfIdx );
		subdict.remove( pkey );

		subdict = dictByPwdResetIdx.get( keyPwdResetIdx );
		subdict.remove( pkey );

		subdict = dictByDefDevIdx.get( keyDefDevIdx );
		subdict.remove( pkey );

	}
	public void deleteSecUserByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argSecUserId )
	{
		CFLibDbKeyHash256 key = schema.getFactorySecUser().newPKey();
		key.setRequiredSecUserId( argSecUserId );
		deleteSecUserByIdIdx( Authorization, key );
	}

	public void deleteSecUserByIdIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		ICFSecSecUser cur;
		LinkedList<ICFSecSecUser> matchSet = new LinkedList<ICFSecSecUser>();
		Iterator<ICFSecSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}

	public void deleteSecUserByULoginIdx( ICFSecAuthorization Authorization,
		String argLoginId )
	{
		CFSecBuffSecUserByULoginIdxKey key = schema.getFactorySecUser().newULoginIdxKey();
		key.setRequiredLoginId( argLoginId );
		deleteSecUserByULoginIdx( Authorization, key );
	}

	public void deleteSecUserByULoginIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByULoginIdxKey argKey )
	{
		ICFSecSecUser cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecUser> matchSet = new LinkedList<ICFSecSecUser>();
		Iterator<ICFSecSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}

	public void deleteSecUserByEMConfIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 argEMailConfirmUuid6 )
	{
		CFSecBuffSecUserByEMConfIdxKey key = schema.getFactorySecUser().newEMConfIdxKey();
		key.setOptionalEMailConfirmUuid6( argEMailConfirmUuid6 );
		deleteSecUserByEMConfIdx( Authorization, key );
	}

	public void deleteSecUserByEMConfIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByEMConfIdxKey argKey )
	{
		ICFSecSecUser cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalEMailConfirmUuid6() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecUser> matchSet = new LinkedList<ICFSecSecUser>();
		Iterator<ICFSecSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}

	public void deleteSecUserByPwdResetIdx( ICFSecAuthorization Authorization,
		CFLibUuid6 argPasswordResetUuid6 )
	{
		CFSecBuffSecUserByPwdResetIdxKey key = schema.getFactorySecUser().newPwdResetIdxKey();
		key.setOptionalPasswordResetUuid6( argPasswordResetUuid6 );
		deleteSecUserByPwdResetIdx( Authorization, key );
	}

	public void deleteSecUserByPwdResetIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByPwdResetIdxKey argKey )
	{
		ICFSecSecUser cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalPasswordResetUuid6() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecUser> matchSet = new LinkedList<ICFSecSecUser>();
		Iterator<ICFSecSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}

	public void deleteSecUserByDefDevIdx( ICFSecAuthorization Authorization,
		CFLibDbKeyHash256 argDfltDevUserId,
		String argDfltDevName )
	{
		CFSecBuffSecUserByDefDevIdxKey key = schema.getFactorySecUser().newDefDevIdxKey();
		key.setOptionalDfltDevUserId( argDfltDevUserId );
		key.setOptionalDfltDevName( argDfltDevName );
		deleteSecUserByDefDevIdx( Authorization, key );
	}

	public void deleteSecUserByDefDevIdx( ICFSecAuthorization Authorization,
		ICFSecSecUserByDefDevIdxKey argKey )
	{
		ICFSecSecUser cur;
		boolean anyNotNull = false;
		if( argKey.getOptionalDfltDevUserId() != null ) {
			anyNotNull = true;
		}
		if( argKey.getOptionalDfltDevName() != null ) {
			anyNotNull = true;
		}
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<ICFSecSecUser> matchSet = new LinkedList<ICFSecSecUser>();
		Iterator<ICFSecSecUser> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<ICFSecSecUser> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableSecUser().readDerivedByIdIdx( Authorization,
				cur.getRequiredSecUserId() );
			deleteSecUser( Authorization, cur );
		}
	}
}
