
// Description: Java 25 in-memory RAM DbIO implementation for ISOCcy.

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
import java.util.*;
import org.apache.commons.codec.binary.Base64;
import io.github.msobkow.v3_1.cflib.*;
import io.github.msobkow.v3_1.cflib.dbutil.*;

import io.github.msobkow.v3_1.cfsec.cfsec.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;
import io.github.msobkow.v3_1.cfsec.cfsecobj.*;

/*
 *	CFSecRamISOCcyTable in-memory RAM DbIO implementation
 *	for ISOCcy.
 */
public class CFSecRamISOCcyTable
	implements ICFSecISOCcyTable
{
	private ICFSecSchema schema;
	private Map< CFSecISOCcyPKey,
				CFSecISOCcyBuff > dictByPKey
		= new HashMap< CFSecISOCcyPKey,
				CFSecISOCcyBuff >();
	private Map< CFSecISOCcyByCcyCdIdxKey,
			CFSecISOCcyBuff > dictByCcyCdIdx
		= new HashMap< CFSecISOCcyByCcyCdIdxKey,
			CFSecISOCcyBuff >();
	private Map< CFSecISOCcyByCcyNmIdxKey,
			CFSecISOCcyBuff > dictByCcyNmIdx
		= new HashMap< CFSecISOCcyByCcyNmIdxKey,
			CFSecISOCcyBuff >();

	public CFSecRamISOCcyTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createISOCcy( CFSecAuthorization Authorization,
		CFSecISOCcyBuff Buff )
	{
		final String S_ProcName = "createISOCcy";
		CFSecISOCcyPKey pkey = schema.getFactoryISOCcy().newPKey();
		pkey.setRequiredISOCcyId( schema.nextISOCcyIdGen() );
		Buff.setRequiredISOCcyId( pkey.getRequiredISOCcyId() );
		CFSecISOCcyByCcyCdIdxKey keyCcyCdIdx = schema.getFactoryISOCcy().newCcyCdIdxKey();
		keyCcyCdIdx.setRequiredISOCode( Buff.getRequiredISOCode() );

		CFSecISOCcyByCcyNmIdxKey keyCcyNmIdx = schema.getFactoryISOCcy().newCcyNmIdxKey();
		keyCcyNmIdx.setRequiredName( Buff.getRequiredName() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByCcyCdIdx.containsKey( keyCcyCdIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOCcyCodeIdx",
				keyCcyCdIdx );
		}

		if( dictByCcyNmIdx.containsKey( keyCcyNmIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ISOCcyNameIdx",
				keyCcyNmIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByCcyCdIdx.put( keyCcyCdIdx, Buff );

		dictByCcyNmIdx.put( keyCcyNmIdx, Buff );

	}

	public CFSecISOCcyBuff readDerived( CFSecAuthorization Authorization,
		CFSecISOCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerived";
		CFSecISOCcyPKey key = schema.getFactoryISOCcy().newPKey();
		key.setRequiredISOCcyId( PKey.getRequiredISOCcyId() );
		CFSecISOCcyBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCcyBuff lockDerived( CFSecAuthorization Authorization,
		CFSecISOCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerived";
		CFSecISOCcyPKey key = schema.getFactoryISOCcy().newPKey();
		key.setRequiredISOCcyId( PKey.getRequiredISOCcyId() );
		CFSecISOCcyBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCcyBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamISOCcy.readAllDerived";
		CFSecISOCcyBuff[] retList = new CFSecISOCcyBuff[ dictByPKey.values().size() ];
		Iterator< CFSecISOCcyBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecISOCcyBuff readDerivedByCcyCdIdx( CFSecAuthorization Authorization,
		String ISOCode )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerivedByCcyCdIdx";
		CFSecISOCcyByCcyCdIdxKey key = schema.getFactoryISOCcy().newCcyCdIdxKey();
		key.setRequiredISOCode( ISOCode );

		CFSecISOCcyBuff buff;
		if( dictByCcyCdIdx.containsKey( key ) ) {
			buff = dictByCcyCdIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCcyBuff readDerivedByCcyNmIdx( CFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerivedByCcyNmIdx";
		CFSecISOCcyByCcyNmIdxKey key = schema.getFactoryISOCcy().newCcyNmIdxKey();
		key.setRequiredName( Name );

		CFSecISOCcyBuff buff;
		if( dictByCcyNmIdx.containsKey( key ) ) {
			buff = dictByCcyNmIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCcyBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCcy.readDerivedByIdIdx() ";
		CFSecISOCcyPKey key = schema.getFactoryISOCcy().newPKey();
		key.setRequiredISOCcyId( ISOCcyId );

		CFSecISOCcyBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCcyBuff readBuff( CFSecAuthorization Authorization,
		CFSecISOCcyPKey PKey )
	{
		final String S_ProcName = "CFSecRamISOCcy.readBuff";
		CFSecISOCcyBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a003" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCcyBuff lockBuff( CFSecAuthorization Authorization,
		CFSecISOCcyPKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecISOCcyBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a003" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecISOCcyBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamISOCcy.readAllBuff";
		CFSecISOCcyBuff buff;
		ArrayList<CFSecISOCcyBuff> filteredList = new ArrayList<CFSecISOCcyBuff>();
		CFSecISOCcyBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a003" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecISOCcyBuff[0] ) );
	}

	public CFSecISOCcyBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		short ISOCcyId )
	{
		final String S_ProcName = "CFSecRamISOCcy.readBuffByIdIdx() ";
		CFSecISOCcyBuff buff = readDerivedByIdIdx( Authorization,
			ISOCcyId );
		if( ( buff != null ) && buff.getClassCode().equals( "a003" ) ) {
			return( (CFSecISOCcyBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecISOCcyBuff readBuffByCcyCdIdx( CFSecAuthorization Authorization,
		String ISOCode )
	{
		final String S_ProcName = "CFSecRamISOCcy.readBuffByCcyCdIdx() ";
		CFSecISOCcyBuff buff = readDerivedByCcyCdIdx( Authorization,
			ISOCode );
		if( ( buff != null ) && buff.getClassCode().equals( "a003" ) ) {
			return( (CFSecISOCcyBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecISOCcyBuff readBuffByCcyNmIdx( CFSecAuthorization Authorization,
		String Name )
	{
		final String S_ProcName = "CFSecRamISOCcy.readBuffByCcyNmIdx() ";
		CFSecISOCcyBuff buff = readDerivedByCcyNmIdx( Authorization,
			Name );
		if( ( buff != null ) && buff.getClassCode().equals( "a003" ) ) {
			return( (CFSecISOCcyBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateISOCcy( CFSecAuthorization Authorization,
		CFSecISOCcyBuff Buff )
	{
		CFSecISOCcyPKey pkey = schema.getFactoryISOCcy().newPKey();
		pkey.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );
		CFSecISOCcyBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateISOCcy",
				"Existing record not found",
				"ISOCcy",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateISOCcy",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecISOCcyByCcyCdIdxKey existingKeyCcyCdIdx = schema.getFactoryISOCcy().newCcyCdIdxKey();
		existingKeyCcyCdIdx.setRequiredISOCode( existing.getRequiredISOCode() );

		CFSecISOCcyByCcyCdIdxKey newKeyCcyCdIdx = schema.getFactoryISOCcy().newCcyCdIdxKey();
		newKeyCcyCdIdx.setRequiredISOCode( Buff.getRequiredISOCode() );

		CFSecISOCcyByCcyNmIdxKey existingKeyCcyNmIdx = schema.getFactoryISOCcy().newCcyNmIdxKey();
		existingKeyCcyNmIdx.setRequiredName( existing.getRequiredName() );

		CFSecISOCcyByCcyNmIdxKey newKeyCcyNmIdx = schema.getFactoryISOCcy().newCcyNmIdxKey();
		newKeyCcyNmIdx.setRequiredName( Buff.getRequiredName() );

		// Check unique indexes

		if( ! existingKeyCcyCdIdx.equals( newKeyCcyCdIdx ) ) {
			if( dictByCcyCdIdx.containsKey( newKeyCcyCdIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOCcy",
					"ISOCcyCodeIdx",
					newKeyCcyCdIdx );
			}
		}

		if( ! existingKeyCcyNmIdx.equals( newKeyCcyNmIdx ) ) {
			if( dictByCcyNmIdx.containsKey( newKeyCcyNmIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateISOCcy",
					"ISOCcyNameIdx",
					newKeyCcyNmIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFSecISOCcyPKey, CFSecISOCcyBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByCcyCdIdx.remove( existingKeyCcyCdIdx );
		dictByCcyCdIdx.put( newKeyCcyCdIdx, Buff );

		dictByCcyNmIdx.remove( existingKeyCcyNmIdx );
		dictByCcyNmIdx.put( newKeyCcyNmIdx, Buff );

	}

	public void deleteISOCcy( CFSecAuthorization Authorization,
		CFSecISOCcyBuff Buff )
	{
		final String S_ProcName = "CFSecRamISOCcyTable.deleteISOCcy() ";
		String classCode;
		CFSecISOCcyPKey pkey = schema.getFactoryISOCcy().newPKey();
		pkey.setRequiredISOCcyId( Buff.getRequiredISOCcyId() );
		CFSecISOCcyBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteISOCcy",
				pkey );
		}
		// Short circuit self-referential code to prevent stack overflows
		Object arrCheckISOCcyCountries[] = schema.getTableISOCtryCcy().readDerivedByCcyIdx( Authorization,
						existing.getRequiredISOCcyId() );
		if( arrCheckISOCcyCountries.length > 0 ) {
			schema.getTableISOCtryCcy().deleteISOCtryCcyByCcyIdx( Authorization,
						existing.getRequiredISOCcyId() );
		}
		CFSecISOCcyByCcyCdIdxKey keyCcyCdIdx = schema.getFactoryISOCcy().newCcyCdIdxKey();
		keyCcyCdIdx.setRequiredISOCode( existing.getRequiredISOCode() );

		CFSecISOCcyByCcyNmIdxKey keyCcyNmIdx = schema.getFactoryISOCcy().newCcyNmIdxKey();
		keyCcyNmIdx.setRequiredName( existing.getRequiredName() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecISOCcyPKey, CFSecISOCcyBuff > subdict;

		dictByPKey.remove( pkey );

		dictByCcyCdIdx.remove( keyCcyCdIdx );

		dictByCcyNmIdx.remove( keyCcyNmIdx );

	}
	public void deleteISOCcyByIdIdx( CFSecAuthorization Authorization,
		short argISOCcyId )
	{
		CFSecISOCcyPKey key = schema.getFactoryISOCcy().newPKey();
		key.setRequiredISOCcyId( argISOCcyId );
		deleteISOCcyByIdIdx( Authorization, key );
	}

	public void deleteISOCcyByIdIdx( CFSecAuthorization Authorization,
		CFSecISOCcyPKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecISOCcyBuff cur;
		LinkedList<CFSecISOCcyBuff> matchSet = new LinkedList<CFSecISOCcyBuff>();
		Iterator<CFSecISOCcyBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCcyBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCcyId() );
			deleteISOCcy( Authorization, cur );
		}
	}

	public void deleteISOCcyByCcyCdIdx( CFSecAuthorization Authorization,
		String argISOCode )
	{
		CFSecISOCcyByCcyCdIdxKey key = schema.getFactoryISOCcy().newCcyCdIdxKey();
		key.setRequiredISOCode( argISOCode );
		deleteISOCcyByCcyCdIdx( Authorization, key );
	}

	public void deleteISOCcyByCcyCdIdx( CFSecAuthorization Authorization,
		CFSecISOCcyByCcyCdIdxKey argKey )
	{
		CFSecISOCcyBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOCcyBuff> matchSet = new LinkedList<CFSecISOCcyBuff>();
		Iterator<CFSecISOCcyBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCcyBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCcyId() );
			deleteISOCcy( Authorization, cur );
		}
	}

	public void deleteISOCcyByCcyNmIdx( CFSecAuthorization Authorization,
		String argName )
	{
		CFSecISOCcyByCcyNmIdxKey key = schema.getFactoryISOCcy().newCcyNmIdxKey();
		key.setRequiredName( argName );
		deleteISOCcyByCcyNmIdx( Authorization, key );
	}

	public void deleteISOCcyByCcyNmIdx( CFSecAuthorization Authorization,
		CFSecISOCcyByCcyNmIdxKey argKey )
	{
		CFSecISOCcyBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecISOCcyBuff> matchSet = new LinkedList<CFSecISOCcyBuff>();
		Iterator<CFSecISOCcyBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecISOCcyBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableISOCcy().readDerivedByIdIdx( Authorization,
				cur.getRequiredISOCcyId() );
			deleteISOCcy( Authorization, cur );
		}
	}
}
