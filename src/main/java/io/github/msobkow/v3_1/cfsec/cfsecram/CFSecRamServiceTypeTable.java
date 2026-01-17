
// Description: Java 25 in-memory RAM DbIO implementation for ServiceType.

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
 *	CFSecRamServiceTypeTable in-memory RAM DbIO implementation
 *	for ServiceType.
 */
public class CFSecRamServiceTypeTable
	implements ICFSecServiceTypeTable
{
	private ICFSecSchema schema;
	private Map< CFSecServiceTypePKey,
				CFSecServiceTypeBuff > dictByPKey
		= new HashMap< CFSecServiceTypePKey,
				CFSecServiceTypeBuff >();
	private Map< CFSecServiceTypeByUDescrIdxKey,
			CFSecServiceTypeBuff > dictByUDescrIdx
		= new HashMap< CFSecServiceTypeByUDescrIdxKey,
			CFSecServiceTypeBuff >();

	public CFSecRamServiceTypeTable( ICFSecSchema argSchema ) {
		schema = argSchema;
	}

	public void createServiceType( CFSecAuthorization Authorization,
		CFSecServiceTypeBuff Buff )
	{
		final String S_ProcName = "createServiceType";
		CFSecServiceTypePKey pkey = schema.getFactoryServiceType().newPKey();
		pkey.setRequiredServiceTypeId( schema.nextServiceTypeIdGen() );
		Buff.setRequiredServiceTypeId( pkey.getRequiredServiceTypeId() );
		CFSecServiceTypeByUDescrIdxKey keyUDescrIdx = schema.getFactoryServiceType().newUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Validate unique indexes

		if( dictByPKey.containsKey( pkey ) ) {
			throw new CFLibPrimaryKeyNotNewException( getClass(), S_ProcName, pkey );
		}

		if( dictByUDescrIdx.containsKey( keyUDescrIdx ) ) {
			throw new CFLibUniqueIndexViolationException( getClass(),
				S_ProcName,
				"ServiceTypeUDescrIdx",
				keyUDescrIdx );
		}

		// Validate foreign keys

		// Proceed with adding the new record

		dictByPKey.put( pkey, Buff );

		dictByUDescrIdx.put( keyUDescrIdx, Buff );

	}

	public CFSecServiceTypeBuff readDerived( CFSecAuthorization Authorization,
		CFSecServiceTypePKey PKey )
	{
		final String S_ProcName = "CFSecRamServiceType.readDerived";
		CFSecServiceTypePKey key = schema.getFactoryServiceType().newPKey();
		key.setRequiredServiceTypeId( PKey.getRequiredServiceTypeId() );
		CFSecServiceTypeBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceTypeBuff lockDerived( CFSecAuthorization Authorization,
		CFSecServiceTypePKey PKey )
	{
		final String S_ProcName = "CFSecRamServiceType.readDerived";
		CFSecServiceTypePKey key = schema.getFactoryServiceType().newPKey();
		key.setRequiredServiceTypeId( PKey.getRequiredServiceTypeId() );
		CFSecServiceTypeBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceTypeBuff[] readAllDerived( CFSecAuthorization Authorization ) {
		final String S_ProcName = "CFSecRamServiceType.readAllDerived";
		CFSecServiceTypeBuff[] retList = new CFSecServiceTypeBuff[ dictByPKey.values().size() ];
		Iterator< CFSecServiceTypeBuff > iter = dictByPKey.values().iterator();
		int idx = 0;
		while( iter.hasNext() ) {
			retList[ idx++ ] = iter.next();
		}
		return( retList );
	}

	public CFSecServiceTypeBuff readDerivedByUDescrIdx( CFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFSecRamServiceType.readDerivedByUDescrIdx";
		CFSecServiceTypeByUDescrIdxKey key = schema.getFactoryServiceType().newUDescrIdxKey();
		key.setRequiredDescription( Description );

		CFSecServiceTypeBuff buff;
		if( dictByUDescrIdx.containsKey( key ) ) {
			buff = dictByUDescrIdx.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceTypeBuff readDerivedByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamServiceType.readDerivedByIdIdx() ";
		CFSecServiceTypePKey key = schema.getFactoryServiceType().newPKey();
		key.setRequiredServiceTypeId( ServiceTypeId );

		CFSecServiceTypeBuff buff;
		if( dictByPKey.containsKey( key ) ) {
			buff = dictByPKey.get( key );
		}
		else {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceTypeBuff readBuff( CFSecAuthorization Authorization,
		CFSecServiceTypePKey PKey )
	{
		final String S_ProcName = "CFSecRamServiceType.readBuff";
		CFSecServiceTypeBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a013" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceTypeBuff lockBuff( CFSecAuthorization Authorization,
		CFSecServiceTypePKey PKey )
	{
		final String S_ProcName = "lockBuff";
		CFSecServiceTypeBuff buff = readDerived( Authorization, PKey );
		if( ( buff != null ) && ( ! buff.getClassCode().equals( "a013" ) ) ) {
			buff = null;
		}
		return( buff );
	}

	public CFSecServiceTypeBuff[] readAllBuff( CFSecAuthorization Authorization )
	{
		final String S_ProcName = "CFSecRamServiceType.readAllBuff";
		CFSecServiceTypeBuff buff;
		ArrayList<CFSecServiceTypeBuff> filteredList = new ArrayList<CFSecServiceTypeBuff>();
		CFSecServiceTypeBuff[] buffList = readAllDerived( Authorization );
		for( int idx = 0; idx < buffList.length; idx ++ ) {
			buff = buffList[idx];
			if( ( buff != null ) && buff.getClassCode().equals( "a013" ) ) {
				filteredList.add( buff );
			}
		}
		return( filteredList.toArray( new CFSecServiceTypeBuff[0] ) );
	}

	public CFSecServiceTypeBuff readBuffByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 ServiceTypeId )
	{
		final String S_ProcName = "CFSecRamServiceType.readBuffByIdIdx() ";
		CFSecServiceTypeBuff buff = readDerivedByIdIdx( Authorization,
			ServiceTypeId );
		if( ( buff != null ) && buff.getClassCode().equals( "a013" ) ) {
			return( (CFSecServiceTypeBuff)buff );
		}
		else {
			return( null );
		}
	}

	public CFSecServiceTypeBuff readBuffByUDescrIdx( CFSecAuthorization Authorization,
		String Description )
	{
		final String S_ProcName = "CFSecRamServiceType.readBuffByUDescrIdx() ";
		CFSecServiceTypeBuff buff = readDerivedByUDescrIdx( Authorization,
			Description );
		if( ( buff != null ) && buff.getClassCode().equals( "a013" ) ) {
			return( (CFSecServiceTypeBuff)buff );
		}
		else {
			return( null );
		}
	}

	public void updateServiceType( CFSecAuthorization Authorization,
		CFSecServiceTypeBuff Buff )
	{
		CFSecServiceTypePKey pkey = schema.getFactoryServiceType().newPKey();
		pkey.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );
		CFSecServiceTypeBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			throw new CFLibStaleCacheDetectedException( getClass(),
				"updateServiceType",
				"Existing record not found",
				"ServiceType",
				pkey );
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() ) {
			throw new CFLibCollisionDetectedException( getClass(),
				"updateServiceType",
				pkey );
		}
		Buff.setRequiredRevision( Buff.getRequiredRevision() + 1 );
		CFSecServiceTypeByUDescrIdxKey existingKeyUDescrIdx = schema.getFactoryServiceType().newUDescrIdxKey();
		existingKeyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		CFSecServiceTypeByUDescrIdxKey newKeyUDescrIdx = schema.getFactoryServiceType().newUDescrIdxKey();
		newKeyUDescrIdx.setRequiredDescription( Buff.getRequiredDescription() );

		// Check unique indexes

		if( ! existingKeyUDescrIdx.equals( newKeyUDescrIdx ) ) {
			if( dictByUDescrIdx.containsKey( newKeyUDescrIdx ) ) {
				throw new CFLibUniqueIndexViolationException( getClass(),
					"updateServiceType",
					"ServiceTypeUDescrIdx",
					newKeyUDescrIdx );
			}
		}

		// Validate foreign keys

		// Update is valid

		Map< CFSecServiceTypePKey, CFSecServiceTypeBuff > subdict;

		dictByPKey.remove( pkey );
		dictByPKey.put( pkey, Buff );

		dictByUDescrIdx.remove( existingKeyUDescrIdx );
		dictByUDescrIdx.put( newKeyUDescrIdx, Buff );

	}

	public void deleteServiceType( CFSecAuthorization Authorization,
		CFSecServiceTypeBuff Buff )
	{
		final String S_ProcName = "CFSecRamServiceTypeTable.deleteServiceType() ";
		String classCode;
		CFSecServiceTypePKey pkey = schema.getFactoryServiceType().newPKey();
		pkey.setRequiredServiceTypeId( Buff.getRequiredServiceTypeId() );
		CFSecServiceTypeBuff existing = dictByPKey.get( pkey );
		if( existing == null ) {
			return;
		}
		if( existing.getRequiredRevision() != Buff.getRequiredRevision() )
		{
			throw new CFLibCollisionDetectedException( getClass(),
				"deleteServiceType",
				pkey );
		}
		// Short circuit self-referential code to prevent stack overflows
		Object arrCheckServiceTypeDeployed[] = schema.getTableService().readDerivedByTypeIdx( Authorization,
						existing.getRequiredServiceTypeId() );
		if( arrCheckServiceTypeDeployed.length > 0 ) {
			schema.getTableService().deleteServiceByTypeIdx( Authorization,
						existing.getRequiredServiceTypeId() );
		}
		CFSecServiceTypeByUDescrIdxKey keyUDescrIdx = schema.getFactoryServiceType().newUDescrIdxKey();
		keyUDescrIdx.setRequiredDescription( existing.getRequiredDescription() );

		// Validate reverse foreign keys

		// Delete is valid
		Map< CFSecServiceTypePKey, CFSecServiceTypeBuff > subdict;

		dictByPKey.remove( pkey );

		dictByUDescrIdx.remove( keyUDescrIdx );

	}
	public void deleteServiceTypeByIdIdx( CFSecAuthorization Authorization,
		CFLibDbKeyHash256 argServiceTypeId )
	{
		CFSecServiceTypePKey key = schema.getFactoryServiceType().newPKey();
		key.setRequiredServiceTypeId( argServiceTypeId );
		deleteServiceTypeByIdIdx( Authorization, key );
	}

	public void deleteServiceTypeByIdIdx( CFSecAuthorization Authorization,
		CFSecServiceTypePKey argKey )
	{
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		CFSecServiceTypeBuff cur;
		LinkedList<CFSecServiceTypeBuff> matchSet = new LinkedList<CFSecServiceTypeBuff>();
		Iterator<CFSecServiceTypeBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecServiceTypeBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableServiceType().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceTypeId() );
			deleteServiceType( Authorization, cur );
		}
	}

	public void deleteServiceTypeByUDescrIdx( CFSecAuthorization Authorization,
		String argDescription )
	{
		CFSecServiceTypeByUDescrIdxKey key = schema.getFactoryServiceType().newUDescrIdxKey();
		key.setRequiredDescription( argDescription );
		deleteServiceTypeByUDescrIdx( Authorization, key );
	}

	public void deleteServiceTypeByUDescrIdx( CFSecAuthorization Authorization,
		CFSecServiceTypeByUDescrIdxKey argKey )
	{
		CFSecServiceTypeBuff cur;
		boolean anyNotNull = false;
		anyNotNull = true;
		if( ! anyNotNull ) {
			return;
		}
		LinkedList<CFSecServiceTypeBuff> matchSet = new LinkedList<CFSecServiceTypeBuff>();
		Iterator<CFSecServiceTypeBuff> values = dictByPKey.values().iterator();
		while( values.hasNext() ) {
			cur = values.next();
			if( argKey.equals( cur ) ) {
				matchSet.add( cur );
			}
		}
		Iterator<CFSecServiceTypeBuff> iterMatch = matchSet.iterator();
		while( iterMatch.hasNext() ) {
			cur = iterMatch.next();
			cur = schema.getTableServiceType().readDerivedByIdIdx( Authorization,
				cur.getRequiredServiceTypeId() );
			deleteServiceType( Authorization, cur );
		}
	}
}
